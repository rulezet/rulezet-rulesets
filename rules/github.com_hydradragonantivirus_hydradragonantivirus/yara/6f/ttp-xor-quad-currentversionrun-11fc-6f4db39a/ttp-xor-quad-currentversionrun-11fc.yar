rule TTP_XOR_QUAD_CurrentVersionRun_11fc {
  strings:
    $key_11fc = { 42 93 [2] 66 9d [2] 4d b1 [2] 63 93 [2] 77 88 [2] 78 92 [2] 66 8f [2] 64 8e [2] 7f 88 [2] 63 8f [2] 7f a0 }

  condition:
    any of them
}