rule TTP_XOR_QUAD_CurrentVersionRun_126a {
  strings:
    $key_126a = { 41 05 [2] 65 0b [2] 4e 27 [2] 60 05 [2] 74 1e [2] 7b 04 [2] 65 19 [2] 67 18 [2] 7c 1e [2] 60 19 [2] 7c 36 }

  condition:
    any of them
}