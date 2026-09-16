rule TTP_XOR_QUAD_CurrentVersionRun_6db1 {
  strings:
    $key_6db1 = { 3e de [2] 1a d0 [2] 31 fc [2] 1f de [2] 0b c5 [2] 04 df [2] 1a c2 [2] 18 c3 [2] 03 c5 [2] 1f c2 [2] 03 ed }

  condition:
    any of them
}