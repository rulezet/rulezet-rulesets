import "pe"
rule nanocore_rat {
  meta:
    author = "jeFF0Falltrades"

  strings:
    $str_nano_1  = "NanoCore.ClientPlugin" wide ascii
    $str_nano_2  = "NanoCore.ClientPluginHost" wide ascii
    $str_plg_1   = "Plugin [{0}] requires an update" wide ascii
    $str_plg_2   = "Plugin [{0}] is being uninstalled" wide ascii
    $str_conn_1  = "PrimaryConnectionHost" wide ascii
    $str_conn_2  = "BackupConnectionHost" wide ascii
    $str_id      = "C8AA-4E06-9D54-CF406F661572" wide ascii
        $load_config = { 02 06 9A 74 54 00 00 01 0B 02 06 17 58 9A 28 3A 00 00 0A }

  condition:
    2 of ($str_*) or $load_config or (pe.timestamp == 1424566177)
}