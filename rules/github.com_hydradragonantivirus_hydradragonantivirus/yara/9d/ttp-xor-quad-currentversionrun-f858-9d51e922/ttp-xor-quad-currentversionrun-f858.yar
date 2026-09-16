rule TTP_XOR_QUAD_CurrentVersionRun_f858 {
  strings:
    $key_f858 = { ab 37 [2] 8f 39 [2] a4 15 [2] 8a 37 [2] 9e 2c [2] 91 36 [2] 8f 2b [2] 8d 2a [2] 96 2c [2] 8a 2b [2] 96 04 }

  condition:
    any of them
}