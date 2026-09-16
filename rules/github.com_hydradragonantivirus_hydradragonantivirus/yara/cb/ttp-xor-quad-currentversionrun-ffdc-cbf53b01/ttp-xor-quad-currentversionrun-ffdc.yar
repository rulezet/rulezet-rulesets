rule TTP_XOR_QUAD_CurrentVersionRun_ffdc {
  strings:
    $key_ffdc = { ac b3 [2] 88 bd [2] a3 91 [2] 8d b3 [2] 99 a8 [2] 96 b2 [2] 88 af [2] 8a ae [2] 91 a8 [2] 8d af [2] 91 80 }

  condition:
    any of them
}