rule TTP_XOR_QUAD_CurrentVersionRun_128c {
  strings:
    $key_128c = { 41 e3 [2] 65 ed [2] 4e c1 [2] 60 e3 [2] 74 f8 [2] 7b e2 [2] 65 ff [2] 67 fe [2] 7c f8 [2] 60 ff [2] 7c d0 }

  condition:
    any of them
}