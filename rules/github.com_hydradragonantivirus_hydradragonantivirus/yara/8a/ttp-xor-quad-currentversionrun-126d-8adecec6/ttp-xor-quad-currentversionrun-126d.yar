rule TTP_XOR_QUAD_CurrentVersionRun_126d {
  strings:
    $key_126d = { 41 02 [2] 65 0c [2] 4e 20 [2] 60 02 [2] 74 19 [2] 7b 03 [2] 65 1e [2] 67 1f [2] 7c 19 [2] 60 1e [2] 7c 31 }

  condition:
    any of them
}