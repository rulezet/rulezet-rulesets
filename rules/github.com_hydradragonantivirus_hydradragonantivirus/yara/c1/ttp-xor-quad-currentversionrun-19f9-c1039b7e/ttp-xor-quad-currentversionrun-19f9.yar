rule TTP_XOR_QUAD_CurrentVersionRun_19f9 {
  strings:
    $key_19f9 = { 4a 96 [2] 6e 98 [2] 45 b4 [2] 6b 96 [2] 7f 8d [2] 70 97 [2] 6e 8a [2] 6c 8b [2] 77 8d [2] 6b 8a [2] 77 a5 }

  condition:
    any of them
}