rule PEiD_00336_Borland_Delphi_3____Portions_Copyright__c__1983_97_Borland__h__ {
  meta:
    description = "[Borland Delphi 3 -> Portions Copyright (c) 1983,97 Borland (h)]"
    ep_only     = "false"

  strings:
    $a = { 50 6F 72 74 69 6F 6E 73 20 43 6F 70 79 72 69 67 68 74 20 28 63 29 20 31 39 38 33 2C 39 37 20 42 6F 72 6C 61 6E 64 00 }

  condition:
    $a
}