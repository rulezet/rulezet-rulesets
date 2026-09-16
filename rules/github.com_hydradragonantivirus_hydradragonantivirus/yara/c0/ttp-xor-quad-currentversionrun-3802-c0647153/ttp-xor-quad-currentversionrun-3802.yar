rule TTP_XOR_QUAD_CurrentVersionRun_3802 {
  strings:
    $key_3802 = { 6b 6d [2] 4f 63 [2] 64 4f [2] 4a 6d [2] 5e 76 [2] 51 6c [2] 4f 71 [2] 4d 70 [2] 56 76 [2] 4a 71 [2] 56 5e }

  condition:
    any of them
}