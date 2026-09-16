rule TTP_XOR_QUAD_CurrentVersionRun_3bdc {
  strings:
    $key_3bdc = { 68 b3 [2] 4c bd [2] 67 91 [2] 49 b3 [2] 5d a8 [2] 52 b2 [2] 4c af [2] 4e ae [2] 55 a8 [2] 49 af [2] 55 80 }

  condition:
    any of them
}