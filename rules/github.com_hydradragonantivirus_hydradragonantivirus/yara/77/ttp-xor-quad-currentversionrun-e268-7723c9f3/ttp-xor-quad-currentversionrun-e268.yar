rule TTP_XOR_QUAD_CurrentVersionRun_e268 {
  strings:
    $key_e268 = { b1 07 [2] 95 09 [2] be 25 [2] 90 07 [2] 84 1c [2] 8b 06 [2] 95 1b [2] 97 1a [2] 8c 1c [2] 90 1b [2] 8c 34 }

  condition:
    any of them
}