rule mal_macos_crossrat_jar {
  meta:
    description = "Identify macOS CrossRAT JAR bundle"
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.03.18"
    reference   = "https://objective-see.org/blog/blog_0x28.html"
    sample      = "15af5bbf3c8d5e5db41fd7c3d722e8b247b40f2da747d5c334f7fd80b715a649"
    DaysofYARA  = "77/100"

  strings:
    $client = "crossrat/client.class"

  condition:
    uint32be(0) == 0x0504B0304 and
    all of them
}