rule PEiD_00271_ASYLUM_Music_File_v_1_0_ {
  meta:
    description = "[ASYLUM Music File v.1.0]"
    ep_only     = "false"

  strings:
    $a = { 41 53 59 4C 55 4D 20 4D 75 73 69 63 20 46 6F 72 6D 61 74 20 56 31 2E 30 00 }

  condition:
    $a
}