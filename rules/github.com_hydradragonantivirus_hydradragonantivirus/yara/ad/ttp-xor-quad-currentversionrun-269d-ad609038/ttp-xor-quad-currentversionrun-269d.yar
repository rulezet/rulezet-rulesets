rule TTP_XOR_QUAD_CurrentVersionRun_269d {
  strings:
    $key_269d = { 75 f2 [2] 51 fc [2] 7a d0 [2] 54 f2 [2] 40 e9 [2] 4f f3 [2] 51 ee [2] 53 ef [2] 48 e9 [2] 54 ee [2] 48 c1 }

  condition:
    any of them
}