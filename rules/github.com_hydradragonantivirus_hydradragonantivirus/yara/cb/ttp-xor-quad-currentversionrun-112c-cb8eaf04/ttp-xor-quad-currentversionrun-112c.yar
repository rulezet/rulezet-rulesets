rule TTP_XOR_QUAD_CurrentVersionRun_112c {
  strings:
    $key_112c = { 42 43 [2] 66 4d [2] 4d 61 [2] 63 43 [2] 77 58 [2] 78 42 [2] 66 5f [2] 64 5e [2] 7f 58 [2] 63 5f [2] 7f 70 }

  condition:
    any of them
}