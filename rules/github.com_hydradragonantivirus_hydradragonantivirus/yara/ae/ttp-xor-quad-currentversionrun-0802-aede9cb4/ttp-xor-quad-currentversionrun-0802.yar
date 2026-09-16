rule TTP_XOR_QUAD_CurrentVersionRun_0802 {
  strings:
    $key_0802 = { 5b 6d [2] 7f 63 [2] 54 4f [2] 7a 6d [2] 6e 76 [2] 61 6c [2] 7f 71 [2] 7d 70 [2] 66 76 [2] 7a 71 [2] 66 5e }

  condition:
    any of them
}