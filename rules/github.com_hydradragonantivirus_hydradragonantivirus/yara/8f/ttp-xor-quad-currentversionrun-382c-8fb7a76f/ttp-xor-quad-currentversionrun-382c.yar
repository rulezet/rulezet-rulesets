rule TTP_XOR_QUAD_CurrentVersionRun_382c {
  strings:
    $key_382c = { 6b 43 [2] 4f 4d [2] 64 61 [2] 4a 43 [2] 5e 58 [2] 51 42 [2] 4f 5f [2] 4d 5e [2] 56 58 [2] 4a 5f [2] 56 70 }

  condition:
    any of them
}