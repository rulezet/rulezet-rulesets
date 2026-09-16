rule PEiD_00292_BDC_HelpSystem_Help_file_ {
  meta:
    description = "[BDC HelpSystem Help file]"
    ep_only     = "false"

  strings:
    $a = "BDC HelpSystem"

  condition:
    $a
}