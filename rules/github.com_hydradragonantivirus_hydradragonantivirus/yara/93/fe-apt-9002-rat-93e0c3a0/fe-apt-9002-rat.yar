rule FE_APT_9002_rat {
  meta:
    author    = "FireEye Labs"
    reference = "https://www.fireeye.com/blog/threat-research/2013/11/operation-ephemeral-hydra-ie-zero-day-linked-to-deputydog-uses-diskless-method.html"

  strings:
    $mz = "MZ"

    $a = "rat_UnInstall" wide ascii

  condition:
    ($mz at 0) and $a

}