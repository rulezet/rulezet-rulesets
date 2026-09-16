rule PEiD_00017_3DMark_Database_file_ {
  meta:
    description = "[3DMark Database file]"
    ep_only     = "false"

  strings:
    $a = "3DMark Database File"

  condition:
    $a
}