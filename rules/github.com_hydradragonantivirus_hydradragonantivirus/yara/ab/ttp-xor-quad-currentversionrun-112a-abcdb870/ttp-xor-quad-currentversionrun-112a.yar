rule TTP_XOR_QUAD_CurrentVersionRun_112a {
  strings:
    $key_112a = { 42 45 [2] 66 4b [2] 4d 67 [2] 63 45 [2] 77 5e [2] 78 44 [2] 66 59 [2] 64 58 [2] 7f 5e [2] 63 59 [2] 7f 76 }

  condition:
    any of them
}