rule TTP_XOR_QUAD_CurrentVersionRun_f78d {
  strings:
    $key_f78d = { a4 e2 [2] 80 ec [2] ab c0 [2] 85 e2 [2] 91 f9 [2] 9e e3 [2] 80 fe [2] 82 ff [2] 99 f9 [2] 85 fe [2] 99 d1 }

  condition:
    any of them
}