rule TTP_XOR_QUAD_CurrentVersionRun_194c {
  strings:
    $key_194c = { 4a 23 [2] 6e 2d [2] 45 01 [2] 6b 23 [2] 7f 38 [2] 70 22 [2] 6e 3f [2] 6c 3e [2] 77 38 [2] 6b 3f [2] 77 10 }

  condition:
    any of them
}