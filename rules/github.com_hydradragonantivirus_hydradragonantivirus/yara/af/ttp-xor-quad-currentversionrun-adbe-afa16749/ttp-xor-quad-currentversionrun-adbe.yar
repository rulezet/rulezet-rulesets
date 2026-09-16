rule TTP_XOR_QUAD_CurrentVersionRun_adbe {
  strings:
    $key_adbe = { fe d1 [2] da df [2] f1 f3 [2] df d1 [2] cb ca [2] c4 d0 [2] da cd [2] d8 cc [2] c3 ca [2] df cd [2] c3 e2 }

  condition:
    any of them
}