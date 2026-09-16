rule TTP_XOR_QUAD_CurrentVersionRun_cc71 {
  strings:
    $key_cc71 = { 9f 1e [2] bb 10 [2] 90 3c [2] be 1e [2] aa 05 [2] a5 1f [2] bb 02 [2] b9 03 [2] a2 05 [2] be 02 [2] a2 2d }

  condition:
    any of them
}