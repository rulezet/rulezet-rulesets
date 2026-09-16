rule TTP_XOR_QUAD_CurrentVersionRun_02f9 {
  strings:
    $key_02f9 = { 51 96 [2] 75 98 [2] 5e b4 [2] 70 96 [2] 64 8d [2] 6b 97 [2] 75 8a [2] 77 8b [2] 6c 8d [2] 70 8a [2] 6c a5 }

  condition:
    any of them
}