rule TTP_XOR_QUAD_CurrentVersionRun_24fc {
  strings:
    $key_24fc = { 77 93 [2] 53 9d [2] 78 b1 [2] 56 93 [2] 42 88 [2] 4d 92 [2] 53 8f [2] 51 8e [2] 4a 88 [2] 56 8f [2] 4a a0 }

  condition:
    any of them
}