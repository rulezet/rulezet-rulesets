rule TTP_XOR_QUAD_CurrentVersionRun_dee0 {
  strings:
    $key_dee0 = { 8d 8f [2] a9 81 [2] 82 ad [2] ac 8f [2] b8 94 [2] b7 8e [2] a9 93 [2] ab 92 [2] b0 94 [2] ac 93 [2] b0 bc }

  condition:
    any of them
}