rule TTP_XOR_QUAD_CurrentVersionRun_0702 {
  strings:
    $key_0702 = { 54 6d [2] 70 63 [2] 5b 4f [2] 75 6d [2] 61 76 [2] 6e 6c [2] 70 71 [2] 72 70 [2] 69 76 [2] 75 71 [2] 69 5e }

  condition:
    any of them
}