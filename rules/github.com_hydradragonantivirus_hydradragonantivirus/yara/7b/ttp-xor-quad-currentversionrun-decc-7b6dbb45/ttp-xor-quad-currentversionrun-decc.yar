rule TTP_XOR_QUAD_CurrentVersionRun_decc {
  strings:
    $key_decc = { 8d a3 [2] a9 ad [2] 82 81 [2] ac a3 [2] b8 b8 [2] b7 a2 [2] a9 bf [2] ab be [2] b0 b8 [2] ac bf [2] b0 90 }

  condition:
    any of them
}