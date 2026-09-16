rule TTP_XOR_QUAD_CurrentVersionRun_37ce {
  strings:
    $key_37ce = { 64 a1 [2] 40 af [2] 6b 83 [2] 45 a1 [2] 51 ba [2] 5e a0 [2] 40 bd [2] 42 bc [2] 59 ba [2] 45 bd [2] 59 92 }

  condition:
    any of them
}