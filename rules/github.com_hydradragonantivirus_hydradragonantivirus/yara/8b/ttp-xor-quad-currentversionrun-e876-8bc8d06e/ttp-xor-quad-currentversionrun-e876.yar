rule TTP_XOR_QUAD_CurrentVersionRun_e876 {
  strings:
    $key_e876 = { bb 19 [2] 9f 17 [2] b4 3b [2] 9a 19 [2] 8e 02 [2] 81 18 [2] 9f 05 [2] 9d 04 [2] 86 02 [2] 9a 05 [2] 86 2a }

  condition:
    any of them
}