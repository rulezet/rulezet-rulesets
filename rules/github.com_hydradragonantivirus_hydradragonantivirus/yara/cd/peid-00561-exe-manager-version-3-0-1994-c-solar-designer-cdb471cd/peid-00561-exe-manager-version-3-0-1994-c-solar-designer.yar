rule PEiD_00561_EXE_Manager_Version_3_0_1994__c__Solar_Designer_ {
  meta:
    description = "[EXE Manager Version 3.0 1994 (c) Solar Designer]"
    ep_only     = "true"

  strings:
    $a = { B4 30 1E 06 CD 21 2E ?? ?? ?? BF ?? ?? B9 ?? ?? 33 C0 2E ?? ?? 47 E2 }

  condition:
    $a
}