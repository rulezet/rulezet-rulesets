rule TTP_XOR_QUAD_CurrentVersionRun_dc3d {
  strings:
    $key_dc3d = { 8f 52 [2] ab 5c [2] 80 70 [2] ae 52 [2] ba 49 [2] b5 53 [2] ab 4e [2] a9 4f [2] b2 49 [2] ae 4e [2] b2 61 }

  condition:
    any of them
}