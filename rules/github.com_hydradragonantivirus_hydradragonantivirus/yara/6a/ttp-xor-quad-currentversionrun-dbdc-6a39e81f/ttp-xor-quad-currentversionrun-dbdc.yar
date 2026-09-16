rule TTP_XOR_QUAD_CurrentVersionRun_dbdc {
  strings:
    $key_dbdc = { 88 b3 [2] ac bd [2] 87 91 [2] a9 b3 [2] bd a8 [2] b2 b2 [2] ac af [2] ae ae [2] b5 a8 [2] a9 af [2] b5 80 }

  condition:
    any of them
}