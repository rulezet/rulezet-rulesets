rule TTP_XOR_QUAD_CurrentVersionRun_62f9 {
  strings:
    $key_62f9 = { 31 96 [2] 15 98 [2] 3e b4 [2] 10 96 [2] 04 8d [2] 0b 97 [2] 15 8a [2] 17 8b [2] 0c 8d [2] 10 8a [2] 0c a5 }

  condition:
    any of them
}