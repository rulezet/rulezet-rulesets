rule TTP_XOR_QUAD_CurrentVersionRun_3d30 {
  strings:
    $key_3d30 = { 6e 5f [2] 4a 51 [2] 61 7d [2] 4f 5f [2] 5b 44 [2] 54 5e [2] 4a 43 [2] 48 42 [2] 53 44 [2] 4f 43 [2] 53 6c }

  condition:
    any of them
}