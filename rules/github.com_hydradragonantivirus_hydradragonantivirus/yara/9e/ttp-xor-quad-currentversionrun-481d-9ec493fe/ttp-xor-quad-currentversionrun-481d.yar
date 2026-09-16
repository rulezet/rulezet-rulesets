rule TTP_XOR_QUAD_CurrentVersionRun_481d {
  strings:
    $key_481d = { 1b 72 [2] 3f 7c [2] 14 50 [2] 3a 72 [2] 2e 69 [2] 21 73 [2] 3f 6e [2] 3d 6f [2] 26 69 [2] 3a 6e [2] 26 41 }

  condition:
    any of them
}