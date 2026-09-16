rule Android {
  meta:
    description = "This is a generic detaction for ANY Android application."
    filetype    = "apk"

  strings:
    $c = "META-INF"
    $d = "AndroidManifest.xml"
    $e = "classes.dex"

  condition:
    all of them
}