rule TTP_XOR_QUAD_CurrentVersionRun_0268 {
  strings:
    $key_0268 = { 51 07 [2] 75 09 [2] 5e 25 [2] 70 07 [2] 64 1c [2] 6b 06 [2] 75 1b [2] 77 1a [2] 6c 1c [2] 70 1b [2] 6c 34 }

  condition:
    any of them
}