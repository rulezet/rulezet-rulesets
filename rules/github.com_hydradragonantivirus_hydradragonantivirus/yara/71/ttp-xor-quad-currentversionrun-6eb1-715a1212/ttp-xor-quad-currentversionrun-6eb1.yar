rule TTP_XOR_QUAD_CurrentVersionRun_6eb1 {
  strings:
    $key_6eb1 = { 3d de [2] 19 d0 [2] 32 fc [2] 1c de [2] 08 c5 [2] 07 df [2] 19 c2 [2] 1b c3 [2] 00 c5 [2] 1c c2 [2] 00 ed }

  condition:
    any of them
}