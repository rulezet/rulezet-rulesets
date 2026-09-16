rule TTP_XOR_QUAD_CurrentVersionRun_31be {
  strings:
    $key_31be = { 62 d1 [2] 46 df [2] 6d f3 [2] 43 d1 [2] 57 ca [2] 58 d0 [2] 46 cd [2] 44 cc [2] 5f ca [2] 43 cd [2] 5f e2 }

  condition:
    any of them
}