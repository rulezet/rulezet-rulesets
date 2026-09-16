rule TTP_XOR_WriteProcessMemory_31be {
  strings:
    $key_31be = { 66 cc [2] 54 ee [2] 52 db [2] 7c db [2] 43 c7 }

  condition:
    any of them
}