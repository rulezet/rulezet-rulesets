rule XProtect_snowdrift {
  meta:
    description = "SNOWDRIFT"

  strings:
    $a = "https://api.pcloud.com/getfilelink?path=%@&forcedownload=1"
    $b = "-[Management initCloud:access_token:]"
    $c = "*.doc;*.docx;*.xls;*.xlsx;*.ppt;*.pptx;*.hwp;*.hwpx;*.csv;*.pdf;*.rtf;*.amr;*.3gp;*.m4a;*.txt;*.mp3;*.jpg;*.eml;*.emlx"

  condition:
    (
      uint32(0) == 0xfeedface or        uint32(0) == 0xcefaedfe or        uint32(0) == 0xfeedfacf or        uint32(0) == 0xcffaedfe or        uint32(0) == 0xcafebabe or        uint32(0) == 0xbebafeca      ) and
    2 of them
}