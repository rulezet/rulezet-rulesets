rule Dragonfly_Query_XML_Code_MAL_DOC {
  meta:
    name = "Query_XML_Code_MAL_DOC"

    author = "other"

  strings:
    $zip_magic = { 50 4b 03 04 }

    $dir = "word/_rels/" ascii

    $dir2 = "word/theme/theme1.xml" ascii

    $style = "word/styles.xml" ascii

  condition:
    $zip_magic at 0 and $dir at 0x0145 and $dir2 at 0x02b7 and $style at 0x08fd

}