rule TTP_XOR_QUAD_CurrentVersionRun_0218 {
  strings:
    $key_0218 = { 51 77 [2] 75 79 [2] 5e 55 [2] 70 77 [2] 64 6c [2] 6b 76 [2] 75 6b [2] 77 6a [2] 6c 6c [2] 70 6b [2] 6c 44 }

  condition:
    any of them
}