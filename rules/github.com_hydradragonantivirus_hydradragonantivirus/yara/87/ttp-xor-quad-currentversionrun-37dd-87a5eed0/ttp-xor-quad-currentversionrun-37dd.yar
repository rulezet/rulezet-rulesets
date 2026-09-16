rule TTP_XOR_QUAD_CurrentVersionRun_37dd {
  strings:
    $key_37dd = { 64 b2 [2] 40 bc [2] 6b 90 [2] 45 b2 [2] 51 a9 [2] 5e b3 [2] 40 ae [2] 42 af [2] 59 a9 [2] 45 ae [2] 59 81 }

  condition:
    any of them
}