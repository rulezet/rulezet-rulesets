rule TTP_XOR_QUAD_CurrentVersionRun_cad2 {
  strings:
    $key_cad2 = { 99 bd [2] bd b3 [2] 96 9f [2] b8 bd [2] ac a6 [2] a3 bc [2] bd a1 [2] bf a0 [2] a4 a6 [2] b8 a1 [2] a4 8e }

  condition:
    any of them
}