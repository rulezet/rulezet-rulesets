rule TTP_XOR_QUAD_CurrentVersionRun_5768 {
  strings:
    $key_5768 = { 04 07 [2] 20 09 [2] 0b 25 [2] 25 07 [2] 31 1c [2] 3e 06 [2] 20 1b [2] 22 1a [2] 39 1c [2] 25 1b [2] 39 34 }

  condition:
    any of them
}