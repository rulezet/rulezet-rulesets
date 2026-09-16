rule TTP_XOR_QUAD_CurrentVersionRun_ef8e {
  strings:
    $key_ef8e = { bc e1 [2] 98 ef [2] b3 c3 [2] 9d e1 [2] 89 fa [2] 86 e0 [2] 98 fd [2] 9a fc [2] 81 fa [2] 9d fd [2] 81 d2 }

  condition:
    any of them
}