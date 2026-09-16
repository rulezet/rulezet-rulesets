rule TTP_XOR_QUAD_CurrentVersionRun_7802 {
  strings:
    $key_7802 = { 2b 6d [2] 0f 63 [2] 24 4f [2] 0a 6d [2] 1e 76 [2] 11 6c [2] 0f 71 [2] 0d 70 [2] 16 76 [2] 0a 71 [2] 16 5e }

  condition:
    any of them
}