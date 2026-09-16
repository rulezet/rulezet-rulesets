rule TTP_XOR_QUAD_CurrentVersionRun_126c {
  strings:
    $key_126c = { 41 03 [2] 65 0d [2] 4e 21 [2] 60 03 [2] 74 18 [2] 7b 02 [2] 65 1f [2] 67 1e [2] 7c 18 [2] 60 1f [2] 7c 30 }

  condition:
    any of them
}